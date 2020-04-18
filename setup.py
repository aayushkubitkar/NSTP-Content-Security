from setuptools import setup, find_packages

setup(
    name="nstpc",
    version="1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Click",
        "protobuf",
        "pynacl",
        "pyduktape",
    ],
    entry_points="""
        [console_scripts]
        nstpc=nstp.client:main
    """,
)
