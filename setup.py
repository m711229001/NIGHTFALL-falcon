from setuptools import setup, find_packages

setup(
    name="nightfall",
    version="1.0.0",
    description="NIGHTFALL — Autonomous AI VAPT Platform",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="NIGHTFALL",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "httpx[http2]>=0.27.0",
        "aiosqlite>=0.20.0",
        "pydantic>=2.7.0",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
        "typer>=0.12.0",
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.30.0",
        "dnslib>=0.9.24",
        "pyjwt[crypto]>=2.8.0",
        "structlog>=24.1.0",
    ],
    extras_require={
        "browser": ["playwright>=1.44.0"],
        "full": [
            "playwright>=1.44.0",
            "aiohttp>=3.9.0",
            "python-Levenshtein>=0.25.0",
            "jinja2>=3.1.4",
        ],
    },
    entry_points={
        "console_scripts": [
            "nightfall=nightfall.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
