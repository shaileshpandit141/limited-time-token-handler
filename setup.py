from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="limited-time-token-handler",
    version="0.1.2",
    author="shailesh",
    author_email="shaileshpandit141@gmail.com",
    description=(
        """
        A Python package designed to handle secure, time-limited token generation and validation.
        It provides functionality for creating and decoding tokens with built-in expiration functionality.
    """
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shaileshpandit141/limited-time-token-handler.git",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=["python-decouple>=3.6", "itsdangerous>=2.1.2"],
    include_package_data=True,
    zip_safe=False,
)
