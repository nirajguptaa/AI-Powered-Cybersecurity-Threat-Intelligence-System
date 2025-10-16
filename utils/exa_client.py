import os
from exa_py import Exa
from dotenv import load_dotenv

load_dotenv()
EXA_API_KEY = os.getenv("EXA_API_KEY")

# Initialize EXA client
exa_client = Exa(api_key=EXA_API_KEY)