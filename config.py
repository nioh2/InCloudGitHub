"""
配置文件 - InCloud GitHub 云上扫描器
"""
import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# GitHub配置
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')

# 扫描配置
SCAN_INTERVAL_HOURS = int(os.getenv('SCAN_INTERVAL_HOURS', 24))
OUTPUT_DIR = os.getenv('OUTPUT_DIR', './scan_reports')

# AI相关的敏感信息模式
SENSITIVE_PATTERNS = [
    # OpenAI API密钥格式
    r'sk-[a-zA-Z0-9]{32,}',
    r'sk-proj-[a-zA-Z0-9_-]{32,}',
    
    # Anthropic API密钥格式
    r'sk-ant-[a-zA-Z0-9_-]{32,}',
    
    # Google AI (Gemini) API密钥格式
    r'AIza[a-zA-Z0-9_-]{35}',
    
    # ===== 常见环境变量名模式 (snake_case) =====
    # AI API Keys
    r'AI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'ai_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # OpenAI
    r'OPENAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'openai_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'OPENAI_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # Anthropic
    r'ANTHROPIC_AUTH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'ANTHROPIC_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'anthropic_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # Claude
    r'CLAUDE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'claude_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # 通用 API Key
    r'API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # Chat API Key
    r'CHAT_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'chat_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # ===== camelCase 和 PascalCase 模式 =====
    # 对象属性赋值: apiKey: "value"
    r'apiKey[\s]*:[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ApiKey[\s]*:[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    
    # 变量赋值: apiKey = "value"
    r'apiKey[\s]*=[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ApiKey[\s]*=[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    
    # chatApiKey 模式
    r'chatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ChatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    
    # openaiApiKey 模式
    r'openaiApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'OpenaiApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'openAIKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    
    # anthropicApiKey 模式
    r'anthropicApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'AnthropicApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    
    # ===== 其他 AI 服务 =====
    # Google AI / Gemini
    r'GOOGLE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'GEMINI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # Hugging Face
    r'HUGGINGFACE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'HF_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # Cohere
    r'COHERE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # Azure OpenAI
    r'AZURE_OPENAI_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'AZURE_OPENAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    
    # ===== 中国 AI 服务 =====
    # DeepSeek
    r'DEEPSEEK_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'deepseek_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'deepseekApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'DeepseekApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    
    # 阿里云百炼 / 通义千问 (Qwen)
    r'DASHSCOPE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'dashscope_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'ALIBABA_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'aliyun_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'QWEN_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'qwen_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'dashscopeApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'DashscopeApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    # 阿里云 AccessKey ID 格式
    r'LTAI[a-zA-Z0-9]{16,20}',
    
    # 智谱 AI (Zhipu / GLM)
    r'ZHIPU_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'zhipu_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'GLM_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'glm_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'ZHIPUAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'zhipuApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ZhipuApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    # 智谱 API Key 格式 (通常以数字开头)
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-zA-Z0-9_-]+',
    
    # MiniMax
    r'MINIMAX_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'minimax_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'MINIMAX_GROUP_ID[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{10,})["\']?',
    r'minimax_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'minimaxApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'MinimaxApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
]

# GitHub搜索关键词
AI_SEARCH_KEYWORDS = [
    'openai api',
    'anthropic claude',
    'gpt api',
    'AI_API_KEY',
    'ANTHROPIC_AUTH_TOKEN',
    'chat_api_key',
    'apiKey',
    'sk-ant-',
    'sk-proj-',
    'OPENAI_API_KEY',
    'chatApiKey',
    # 中国 AI 服务
    'deepseek api',
    'dashscope',
    'qwen api',
    'zhipu api',
    'glm api',
    'minimax api',
    'DEEPSEEK_API_KEY',
    'DASHSCOPE_API_KEY',
    'ZHIPU_API_KEY',
    'MINIMAX_API_KEY',
]

# 要排除的文件扩展名
EXCLUDED_EXTENSIONS = [
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
    '.mp4', '.avi', '.mov', '.wmv',
    '.zip', '.tar', '.gz', '.rar',
    '.exe', '.dll', '.so', '.dylib',
    '.pdf', '.doc', '.docx',
]

# 要排除的目录
EXCLUDED_DIRS = [
    'node_modules',
    '.git',
    'dist',
    'build',
    '__pycache__',
    'venv',
    'env',
]

# GitHub API速率限制
MAX_REPOS_PER_SEARCH = 100
SEARCH_DELAY_SECONDS = 2
