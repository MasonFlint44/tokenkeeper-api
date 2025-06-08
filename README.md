# UV Devcontainer Template

This template is designed to streamline the setup of a Python development environment using the `uv` package manager on Debian Bookworm. It's equipped with a collection of tools and extensions specifically chosen to enhance the Python development workflow, from code writing to testing and deployment.

## Features Overview

| Feature                 | Description                                                                                           |
|-------------------------|-------------------------------------------------------------------------------------------------------|
| **Operating System**    | Debian Bookworm, providing a stable foundation for development.                                       |
| **Package Management**  | `uv`, a lightweight and efficient package and environment manager.                                    |
| **Programming Language**| Python, ready for development right out of the box.                                                  |
| **Version Control**     | Git integrated for robust version control.                                                           |
| **VSCode Extensions**   | A curated list of VSCode extensions installed, including essentials for Python development.           |
| **Testing Framework**   | Pytest configured to run tests from the `tests` directory, utilizing VSCode's test runner for ease of testing. |

## Getting Started

1. **Clone and Open**: Clone this repository and open it in VSCode. The project will prompt to reopen in a devcontainer.
1. **Dev Environment Initialization**: The `uv sync` task can be run manually, preparing and updating your development environment.
1. **Rename the Project Directory**: Rename the `/project` directory to match the name of your new project to get started. Update the project name in the pyproject.toml file as well.

## Managing Dependencies

- **Application Dependencies**: Defined in `pyproject.toml`. A frozen set of these dependencies is created and stored in `uv.lock` for reproducible deployments.

## Running Tests

Tests are run using VSCode's integrated test runner:

1. Navigate to the testing sidebar in VSCode.
1. You'll see your tests listed there. Test can be run directly from the UI.

## Running the Application

VSCode's `launch.json` is configured to debug the currently open Python file, allowing you to run and debug any part of your project easily.

> Note: You may need to tweak `launch.json` for specific project requirements, such as adding arguments or setting environment variables.

### Quick Start

- Open `project/main.py` or any Python file you intend to run.
- Use `F5` or the green play button in the "Run and Debug" sidebar to start debugging.

## Deployment

Deploy your application using the dependencies detailed in `uv.lock` to guarantee that your deployment mirrors the tested state of your application.

## Contributing

We welcome contributions to improve the `uv-devcontainer-template`. Please follow the standard fork and pull request workflow. Make sure to add tests for new features and update the documentation as necessary.

## License

This project is licensed under the [MIT License](LICENSE.md).
