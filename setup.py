"""
AstraVulnX v3.0.0 - Setup Configuration
Author: Meheraz Hosen Siam
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="astravulnx",
    version="3.0.0",
    author="Meheraz Hosen Siam",
    author_email="meheraz.siam@example.com",
    description="AI-Powered Web Vulnerability Scanner - OWASP Top 10 Detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/meherazhosensiam/-AstraVulnX-Scan",
    project_urls={
        "Bug Tracker": "https://github.com/meherazhosensiam/-AstraVulnX-Scan/issues",
        "Documentation": "https://github.com/meherazhosensiam/-AstraVulnX-Scan#readme",
        "Source Code": "https://github.com/meherazhosensiam/-AstraVulnX-Scan",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.8.0",
        "requests>=2.28.0",
        "beautifulsoup4>=4.12.0",
        "reportlab>=4.0.0",
        "colorama>=0.4.6",
        "asyncio>=3.4.3",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "astravulnx=main:main",
        ],
    },
    keywords="security vulnerability scanner owasp penetration-testing web-security sql-injection xss ssrf",
)
