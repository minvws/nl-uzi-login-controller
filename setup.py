from setuptools import setup, find_packages

__version__ = "0.0.1"

requirements = [
    "fastapi",
    "requests",
    "redis",
    "jinja2",
    "jwcrypto",
    "setuptools",
    "asn1crypto",
    "pycryptodomex",
    "pUzi @ git+ssh://git@github.com/minvws/pUzi-python"
]

setup(
    name="app",
    version=__version__,
    packages=find_packages(),
    package_dir={"app": "app"},
    package_data={"app": ["templates/saml/html/*.html"]},
    install_requires=requirements,
    extras_require={
        "dev": [
            "black",
            "uvicorn",
            "pylint",
            "bandit",
            "mypy",
            "autoflake",
            "coverage",
            "coverage-badge",
            "pytest",
            "types-requests",
            "types-redis"
        ]
    },
)
