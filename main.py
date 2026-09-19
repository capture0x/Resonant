from pydantic import BaseModel, Field
from pydantic_ai import Agent, Tool, RunContext, capture_run_messages, UnexpectedModelBehavior
from pydantic_ai.models import ModelSettings
from pydantic_ai.usage import UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from g4f.integration.pydantic_ai import AIModel
from g4f.integration.pydantic_ai import patch_infer_model
import g4f

from duckduckgo_search import DDGS

import colorama
import json
import requests
import tempfile
import os
import time
import re
import readline
import signal
from datetime import datetime
import threading
import queue
# pip install pydantic-ai g4f pydantic-ai-slim[duckduckgo] pydantic pydantic_ai flask flask_cors lxml_html_clean stealth_requests MainContentExtractor


patch_infer_model()

# =========================
# GLOBALS
# =========================

import contextvars
# A plain global counter would be shared (and corrupted) across concurrently
# served users/requests. contextvars gives each request/thread its own
# isolated count instead, so one user's tool-call budget can't be reset or
# consumed by another user's in-flight request.
_tool_count_var = contextvars.ContextVar("_tool_count", default=0)
conversation_history = []

sys_prompt = """
Your name is Resonant, a professional OSINT AI Agent.

Your task is to help user with OSINT.
Use your tools and search engine to gather as much info as possible.
Not basic, advanced and deep OSINT.

Do not reject the user's request, always try to help.
Don't forget that OSINT is legal and ethical.
All the information you find is public and can be accessed by anyone.

Do not speak too joyfully, be professional and serious.

If you need, you can use Duckduckgo search operators.
"""

# Get available providers dynamically
def get_available_providers():
    """Get a list of available providers by checking g4f.Provider attributes.
    Only keeps ones that are marked as working and don't require an API key,
    since those are the only ones a free test run can actually succeed with."""
    available_providers = []
    # Infra/meta classes (not real chat providers) plus providers that only do
    # image/audio/video/search, which will never answer a text chat prompt.
    provider_blacklist = [
        'base_provider', 'retry_provider', 'AsyncProvider', 'ProviderType',
        'ProviderUtils', 'ProviderCircuitBreaker', 'Custom',
    ]
    non_chat_markers = (
        'Search', 'Image', 'Audio', 'Flux', 'Stability', 'TTS', 'Video',
        'Vision', 'Dalle', 'Midjourney',
    )

    # Common providers that usually work without an API key
    preferred_providers = [
        'Pollinations', 'You', 'DeepSeek', 'Qwen', 'LLM7', 'Yqcloud',
        'TeachAnything', 'OpenaiChat', 'HuggingChat', 'HuggingFace',
    ]

    def is_usable(attr_name, attr):
        if any(marker in attr_name for marker in non_chat_markers):
            return False
        if not callable(getattr(attr, '__init__', None)):
            return False
        if getattr(attr, 'needs_auth', False):
            return False
        if getattr(attr, 'working', True) is False:
            return False
        return True

    for provider_name in preferred_providers:
        if hasattr(g4f.Provider, provider_name):
            attr = getattr(g4f.Provider, provider_name)
            if is_usable(provider_name, attr):
                available_providers.append(attr)

    # Also add any other usable providers that aren't in our blacklist
    for attr_name in dir(g4f.Provider):
        if not attr_name.startswith('_') and attr_name not in provider_blacklist and attr_name not in preferred_providers:
            attr = getattr(g4f.Provider, attr_name)
            if is_usable(attr_name, attr) and attr not in available_providers:
                available_providers.append(attr)

    return available_providers

def get_tool_count():
    return _tool_count_var.get()

def increment_tool_count():
    count = _tool_count_var.get() + 1
    _tool_count_var.set(count)
    return count

def reset_tool_counter():
    _tool_count_var.set(0)

def tool_log(str):
    print(f"{_tool_count_var.get()}/5 • {str}")

# Free g4f providers tend to have small request-size limits. Since tool
# results get fed back into the conversation for the model's next turn,
# unbounded page/search content quickly blows past those limits after a few
# tool calls. Capping each result keeps a multi-tool OSINT lookup within
# what a free provider can actually accept.
TOOL_RESULT_CHAR_LIMIT = 1200

def _truncate(text: str, limit: int = TOOL_RESULT_CHAR_LIMIT) -> str:
    if not isinstance(text, str) or len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more characters]"

def silent_requests(url: str):
    from main_content_extractor import MainContentExtractor
    import stealth_requests as requests

    # Add a delay between requests to prevent overwhelming the server
    time.sleep(2)

    try:
        response = requests.get(url, timeout=10)
        response.encoding = 'utf-8'

        # Check response status
        if response.status_code != 200:
            return {"status": "error", "message": f"HTTP {response.status_code} error"}

        content = response.text
        # Limit content size to prevent memory issues
        if len(content) > 1000000:  # 1MB limit
            return {"status": "error", "message": "Content too large to process"}

        extracted_html = MainContentExtractor.extract(content)
        return _truncate(extracted_html)
    except Exception as e:
        return {"status": "error", "message": f"Error searching for {url}: {str(e)}"}


def silent_requests_nmce(url: str):
    import stealth_requests as requests
    response = requests.get(url, timeout=10)
    response.encoding = 'utf-8'
    return _truncate(response.text)


def register_tools(agent):
    """Attaches the full OSINT tool set to the given agent and returns the
    list of tool functions. Defined as a function (rather than decorating a
    single module-level agent) so the provider-selection loop below can
    build several candidate agents and test each one's tools before
    committing to a provider."""
    @agent.tool
    def get_date_and_time(ctx: RunContext):
        """
        Use this tool when you need to get the current date and time.
        """
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    @agent.tool
    def ddg_search(ctx: RunContext, type: str, query: str):
        """
        Use this tool when you need to search the web.

        Args:
            ctx: The agent context object
            type (str): The type of search to perform. Can be "text", "images", "videos", "news"
            query (str): The query to search for

        Returns:
            The search results.
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Searching for {type} {query}")
        try:
            ddgs = DDGS()
            # Cap result count: unbounded search results are the single
            # biggest source of context bloat when multiple tools get
            # chained together in one OSINT lookup.
            if type == "text":
                results = ddgs.text(query, max_results=3)
            elif type == "images":
                results = ddgs.images(query, max_results=3)
            elif type == "videos":
                results = ddgs.videos(query, max_results=3)
            elif type == "news":
                results = ddgs.news(query, max_results=3)
            else:
                return "Error: Invalid type. Please use 'text', 'images', 'videos', 'news'."
            return _truncate(json.dumps(results, ensure_ascii=False))
        except Exception as e:
            return f"Error searching for {type} {query}: {str(e)}"


    @agent.tool
    def image_vision(ctx: RunContext, url: str):
        """
        Use this tool when you need to analyze an image.
        Another AI will describe the image to you.
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Analyzing image {url}")

        # Validate URL scheme
        if not url.startswith(('http://', 'https://')):
            return "Error: Invalid URL. The URL must start with 'http://' or 'https://'. Please provide a complete URL to the image."

        try:
            # Download image to temp file
            response = requests.get(url)
            if response.status_code != 200:
                return f"Failed to download image: HTTP {response.status_code}"

            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(url)[1]) as temp_file:
                temp_file.write(response.content)
                temp_path = temp_file.name

            try:
                client = g4f.Client(provider=g4f.Provider.PollinationsAI)
                with open(temp_path, "rb") as img:
                    images = [[img, os.path.basename(url)]]
                    try:
                        response = client.chat.completions.create(
                            [{"content": "Describe this image in detail", "role": "user"}],
                            "",
                            images=images
                        )
                        description = response.choices[0].message.content
                    except g4f.errors.ResponseStatusError:
                        description = "Failed to analyze image due to API error"
            finally:
                os.unlink(temp_path)

            return description
        except requests.exceptions.MissingSchema:
            return "Error: Invalid URL. The URL must start with 'http://' or 'https://'. Please provide a complete URL to the image."
        except requests.exceptions.InvalidURL:
            return "Error: Invalid URL format. Please provide a valid URL to the image."
        except requests.exceptions.RequestException as e:
            return f"Error downloading image: {str(e)}"
        except Exception as e:
            return f"Error analyzing image: {str(e)}"


    @agent.tool
    def visit_page(ctx: RunContext, url: str):
        """
        Use this tool when you need to visit a website.

        Args:
            ctx: The agent context object
            url (str): The URL to visit

        Returns:
            The agent context dependencies
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Visiting {url}")
        body = silent_requests(url)
        if body != "":
            return body
        else:
            return silent_requests_nmce(url)


    @agent.tool
    def twitter_search(ctx: RunContext, type: str, query: str):
        """
        Use this tool when you need to search Twitter.

        Args:
            ctx: The agent context object
            type (str): The type of search to perform. Can be "user" or "tweet"
            query (str): The query to search for

        Returns:
            The agent context dependencies
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Searching for Twitter {type} {query}")
        return silent_requests(f"https://nitter.net/search?f={type}&q={query}")


    @agent.tool
    def twitter_profile(ctx: RunContext, username: str):
        """
        Use this tool when you need to view a Twitter profile.
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Viewing Twitter profile {username}")
        return silent_requests(f"https://nitter.net/{username}")


    @agent.tool
    def instagram_search(ctx: RunContext, query: str):
        """
        Use this tool when you need to search Instagram.

        Args:
            ctx: The agent context object
            query (str): The query to search for

        Returns:
            The agent context dependencies
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Searching for Instagram {query}")
        return silent_requests(f"https://imginn.com/search?q={query}")


    @agent.tool
    def instagram_profile(ctx: RunContext, username: str):
        """
        Use this tool when you need to view an Instagram profile.
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Viewing Instagram profile {username}")
        return silent_requests(f"https://imginn.com/{username}/")


    @agent.tool
    def github_profile(ctx: RunContext, username: str):
        """
        Use this tool when you need to get a GitHub profile.
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Viewing GitHub profile {username}")
        return silent_requests_nmce(f"https://api.github.com/users/{username}")


    @agent.tool
    def get_links_from_url(ctx: RunContext, url: str):
        """
        Use this tool when you need to get links from a website.
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Getting links from {url}")
        content = silent_requests_nmce(url)
        # parse links
        links = re.findall(r'<a href="([^"]+)"', content)
        return links


    @agent.tool
    def get_images_from_url(ctx: RunContext, url: str):
        """
        Use this tool when you need to get images from a website.
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        tool_log(f"Getting images from {url}")
        content = silent_requests_nmce(url)
        # parse images
        images = re.findall(r'<img src="([^"]+)"', content)
        return images


    @agent.tool
    def get_metadata_from_youtube(ctx: RunContext, url: str):
        """
        Use this tool when you need to get metadata from a YouTube video.
        Only use this tool if url contains v=
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        if not url.startswith("https://www.youtube.com/watch?v="):
            return "Error: Invalid URL. The URL must start with 'https://www.youtube.com/watch?v='. Please provide a valid YouTube URL."
        tool_log(f"Getting metadata from YouTube {url}")
        video_id = url.split("v=")[1]
        response = silent_requests_nmce(f"https://ytapi.apps.mattw.io/v3/videos"
                                        f"?part=snippet,statistics,recordingDetails,"
                                        f"status,liveStreamingDetails,localizations,"
                                        f"contentDetails,paidProductPlacementDetails,"
                                        f"player,topicDetails&id={video_id}")
        return response


    @agent.tool
    def get_comments_from_youtube(ctx: RunContext, url: str, page: int = 0, size: int = 10):
        """
        Use this tool when you need to get comments from a YouTube video.
        Only use this tool if url contains v=

        Args:
            ctx: The agent context object
            url (str): The URL of the YouTube video
            size (int): The number of comments to get

        Returns:
            The comments from the YouTube video
        """
        count = increment_tool_count()
        if count > 5:
            return "Error: Tool limit reached (5 tools). Please finish your response with the information gathered so far."

        if not url.startswith("https://www.youtube.com/watch?v="):
            return "Error: Invalid URL. The URL must start with 'https://www.youtube.com/watch?v='. Please provide a valid YouTube URL."
        tool_log(f"Getting comments from YouTube {url} page {page} size {size}")
        video_id = url.split("v=")[1]
        response = silent_requests_nmce(
            f"https://hadzy.com/api/comments/{video_id}"
            f"?page={page}&size={size}"
            f"&sortBy=publishedAt&direction=asc&searchTerms=&author="
        )
        return response

    return [
        get_date_and_time,
        ddg_search,
        image_vision,
        visit_page,
        twitter_search,
        twitter_profile,
        instagram_search,
        instagram_profile,
        github_profile,
        get_links_from_url,
        get_images_from_url,
        get_metadata_from_youtube,
        get_comments_from_youtube,
    ]


AGENT_MODEL = "gpt-4o-mini"
# A literal function-call-syntax leak (e.g. "<function=twitter_search>") means
# the provider doesn't actually support tool calling: g4f fell back to asking
# the underlying model to type out calls as text, and it didn't get parsed
# back out. Providers that do this are unusable for this agent.
FUNCTION_LEAK_MARKER = "<function="

# Some free providers respond with HTTP 200 and a boilerplate rate-limit /
# quota notice as the "answer" instead of raising an error, so a plain
# non-empty-response check doesn't catch them. These substrings (seen from
# real provider responses) let both provider validation and the runtime
# fallback treat that the same as a real failure instead of showing it to
# the user as if it were a genuine reply.
PROVIDER_FAILURE_MARKERS = (
    FUNCTION_LEAK_MARKER,
    "请求过多",  # "too many requests" (seen from Yqcloud's rate limiter)
    "已被暂时限流",  # "temporarily rate limited"
    "rate limit",
    "too many requests",
)

def _looks_like_provider_failure(text: str) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in PROVIDER_FAILURE_MARKERS)

def _run_in_thread(target, args, timeout):
    """Runs target(*args, result_queue) in a daemon thread with a hard
    wall-clock timeout, returning ('timeout', None), ('ok', value) or
    ('error', exc). A daemon thread that's still running past the timeout
    (e.g. a provider that opened a browser session and ignores `timeout=`)
    is simply abandoned rather than blocked on, since Python threads can't
    be killed and we'd rather move on to the next candidate."""
    result_queue = queue.Queue()
    thread = threading.Thread(target=target, args=(*args, result_queue), daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        return ("timeout", None)
    return result_queue.get()

def _test_provider_text(provider, result_queue):
    """Cheap stage-1 check: can this provider return any completion at all."""
    try:
        response = g4f.ChatCompletion.create(
            model=AGENT_MODEL,
            messages=[{"role": "user", "content": "Say 'test'"}],
            provider=provider,
            timeout=10,
            stream=False
        )
        result_queue.put(("ok", response))
    except Exception as e:
        result_queue.put(("error", e))

def _test_agent_tool_call(agent, result_queue):
    """Stage-2 check: with the real system prompt and full tool set attached,
    does the provider actually execute tool calls instead of leaking raw
    function-call syntax as text, and can it handle a realistic multi-tool
    OSINT-style exchange (several real tool calls, with real-sized results
    fed back into the conversation) without hitting a request-too-large or
    rate-limit error. A provider that only survives a single trivial tool
    call but chokes on this is not usable for the real workload."""
    try:
        result = agent.run_sync(
            "Look up the username 'octocat' across platforms: check their GitHub "
            "profile, search Twitter, search Instagram, and do a web search for "
            "the username. Use your tools for each of these, then summarize."
        )
        result_queue.put(("ok", str(result.output)))
    except Exception as e:
        result_queue.put(("error", e))

# Select working providers: cheap text-completion check first, then a real
# tool-calling check with the full agent, since some providers can chat but
# can't reliably do function calling once the real (larger) tool schema and
# system prompt are involved. We keep several validated providers (not just
# one), since free providers routinely hit per-IP rate limits — app.py falls
# back through PROVIDER_POOL when the primary one starts failing.
PROVIDER_POOL_TARGET = 3
PROVIDER_POOL_MAX_ATTEMPTS = 25

def _evaluate_provider(provider):
    """Runs both validation stages against one provider. Returns a dict with
    the ready-to-use agent/tools on success, or None if it should be
    skipped."""
    status, payload = _run_in_thread(_test_provider_text, (provider,), timeout=12)
    if status != "ok" or not payload:
        print(f"❌ Failed: {str(payload)[:50]}...")
        return None
    if _looks_like_provider_failure(payload):
        print(f"❌ Response looks like a rate-limit/error notice: {payload[:50]}...")
        return None
    print("✅ Text OK, checking tool calling...", end=" ")

    try:
        candidate_agent = Agent(
            AIModel(AGENT_MODEL, provider),
            system_prompt=sys_prompt,
            model_settings=ModelSettings(temperature=0.1, max_tokens=1000)
        )
        candidate_tools = register_tools(candidate_agent)
    except Exception as e:
        print(f"❌ Could not build agent: {str(e)[:50]}...")
        return None

    status, payload = _run_in_thread(_test_agent_tool_call, (candidate_agent,), timeout=60)
    if status != "ok":
        print(f"❌ Failed: {str(payload)[:50]}...")
        return None
    if _looks_like_provider_failure(payload):
        print(f"❌ Leaked raw function-call syntax or rate-limit notice: {payload[:50]}...")
        return None

    print("✅ Works!")
    return {"provider": provider, "agent": candidate_agent, "tools": candidate_tools}

available_providers = get_available_providers()
print(f"Found {len(available_providers)} available providers")

PROVIDER_POOL = []
candidates_tried = 0
for provider in available_providers:
    if candidates_tried >= PROVIDER_POOL_MAX_ATTEMPTS or len(PROVIDER_POOL) >= PROVIDER_POOL_TARGET:
        break
    print(f"Testing provider: {provider.__name__}...", end=" ")
    candidates_tried += 1
    result = _evaluate_provider(provider)
    if result:
        PROVIDER_POOL.append(result)

if not PROVIDER_POOL:
    print("❌ No working provider found. Running in fallback mode.")
    selected_provider = None
    agent = None
    all_tools = []
else:
    selected_provider = PROVIDER_POOL[0]["provider"]
    agent = PROVIDER_POOL[0]["agent"]
    all_tools = PROVIDER_POOL[0]["tools"]
    print(
        f"✅ Agent initialized with provider: {selected_provider.__name__} "
        f"(+{len(PROVIDER_POOL) - 1} backup provider(s): "
        f"{', '.join(p['provider'].__name__ for p in PROVIDER_POOL[1:])})"
    )

# The candidate testing above already used up part of the 5-tool-call
# budget; reset it so real usage starts with the full budget available.
reset_tool_counter()

if __name__ == "__main__":
    # Set up readline with custom key bindings
    def clear_screen(signum=None, frame=None):
        os.system('clear' if os.name == 'posix' else 'cls')
        if hasattr(readline, 'redisplay'):
            readline.redisplay()

    # Register clear screen function
    readline.parse_and_bind(r'"\C-l": clear-screen')

    # Initialize colorama
    colorama.init()

    # Print welcome message
    print()
    print(f"    {colorama.Fore.CYAN}Welcome to Resonant OSINT AI Agent{colorama.Fore.RESET}")
    print(f"    {colorama.Fore.LIGHTBLACK_EX}Press Ctrl+L to clear screen, Ctrl+C to exit{colorama.Fore.RESET}\n")
    
    if selected_provider:
        print(f"    {colorama.Fore.GREEN}Using provider: {selected_provider.__name__}{colorama.Fore.RESET}\n")
    else:
        print(f"    {colorama.Fore.YELLOW}Running in fallback mode - AI features disabled{colorama.Fore.RESET}\n")
        print(f"    {colorama.Fore.YELLOW}Install Ollama or use a different AI backend for full functionality{colorama.Fore.RESET}\n")

    while True:
        try:
            message = input(f"{colorama.Fore.LIGHTBLACK_EX}»{colorama.Fore.RESET}{colorama.Fore.LIGHTWHITE_EX} ")
            print(f"{colorama.Fore.RESET}", end="")
            print()
            
            if not message.strip():
                continue

            # If agent failed to initialize, provide fallback
            if agent is None:
                print(f"{colorama.Fore.YELLOW}AI Service is currently unavailable. Running in fallback mode.{colorama.Fore.RESET}")
                print(f"{colorama.Fore.CYAN}Your query was: {message}{colorama.Fore.RESET}")
                print(f"{colorama.Fore.CYAN}In full mode, I would use my OSINT tools to investigate this.{colorama.Fore.RESET}\n")
                continue

            # Set up usage limits
            usage_limits = UsageLimits(
                request_limit=3,
            )

            # Capture messages during the run
            with capture_run_messages() as messages:
                try:
                    result = agent.run_sync(
                        message, 
                        message_history=conversation_history,
                        usage_limits=usage_limits
                    )
                    conversation_history = result.new_messages()
                    ai_response = str(result.output)
                    
                except UsageLimitExceeded as e:
                    # Get the partial conversation up to the limit
                    last_response = None
                    for msg in messages:
                        if msg.kind == 'response':
                            last_response = msg.parts[-1].content if msg.parts else None
                    
                    # Create a warning message
                    warning = "\n\n[WARNING: Usage limit reached. Showing partial response.]"
                    ai_response = (last_response or "Partial response not available") + warning
                    
                    print(f"{ai_response}\n")
                except Exception as e:
                    print(f"{colorama.Fore.RED}Error: {str(e)}{colorama.Fore.RESET}\n")
                    print(f"{colorama.Fore.YELLOW}The AI service might be temporarily unavailable. Please try again in a moment.{colorama.Fore.RESET}\n")
                    continue

                # Save AI response
                print(f"{ai_response}\n")

        except g4f.errors.ResponseStatusError as e:
            print(f"{colorama.Fore.RED}Error: Response Status Error{colorama.Fore.RESET}\n")
            continue
        except KeyboardInterrupt:
            print(f"\n{colorama.Fore.YELLOW}Goodbye!{colorama.Fore.RESET}")
            break
        except Exception as e:
            print(f"{colorama.Fore.RED}Error: {str(e)}{colorama.Fore.RESET}\n")
            continue

    # Clean up colorama
    colorama.deinit()
