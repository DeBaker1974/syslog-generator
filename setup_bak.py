# setup.py
"""Setup script for the syslog generator package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="syslog-generator",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A tool for generating realistic syslog messages for testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/syslog-generator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Logging",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=6.0",
        "faker>=18.0.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "pylint>=2.17.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "syslog-generator=syslog_generator.main:main",
        ],
    },
)
