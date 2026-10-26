import os
from setuptools import setup, find_packages

# قراءة وصف المشروع التفصيلي من README.md للظهور في صفحة PyPI
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="hailab-fail-closed-engine",
    version="0.1.0",
    description="Deterministic zeroization & autonomous fail-closed security engine.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Waleed Mubarak | HAI Lab",
    author_email="waleedmubarak@substack.com", # يُفضل إدراج البريد الرسمي للمطور
    url="https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-",
    project_urls={
        "Documentation": "https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-#readme",
        "Source": "https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-",
        "Tracker": "https://github.com/Waleed-Mubarak/hailab-fail-closed-engine-/issues",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="security fail-closed zeroization middleware cryptography hailab",
)
