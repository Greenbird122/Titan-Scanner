"""Titan — setup.py fallback for older pip versions."""
from setuptools import find_packages, setup

setup(
    name="titan-scanner",
    version="1.0.0",
    description="Titan — Autonomous Penetration Testing Platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Titan Security Lab",
    url="https://github.com/titan-security-lab/titan",
    packages=find_packages(exclude=["tests*", "docs*"]),


    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "PyJWT>=2.8.0",
    ],
    extras_require={
        "full": ["playwright>=1.40.0", "flask>=3.0.0"],
        "dev": ["pytest>=7.4.0", "pytest-asyncio>=0.21.0"],
    },
    entry_points={
        "console_scripts": [
            "tscan=titan.tscan_main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
