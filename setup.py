# setup.py
from setuptools import setup, find_packages

setup(
    name="xhcloud",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "typer",
        "httpx",
        "pyyaml"
    ],
    entry_points={
        "console_scripts": [
            "xhcloud=xhcloud.cli:app",
        ],
    },
)
