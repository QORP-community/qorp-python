import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="qorp",
    version="0.0.0.dev0",
    author="jorektheglitch",
    author_email="jorektheglitch@yandex.ru",
    description="QORP protocol implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jorektheglitch/qorp-python",
    package_dir={"qorp": "qorp"},
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=["cryptography>=37"]
)
