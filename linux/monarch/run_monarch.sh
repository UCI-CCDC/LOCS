#!/bin/sh

# Exit immediately if a command exits with a non-zero status
set -e

# Create a virtual environment named 'venv' if it doesn't exist
if [ ! -d "venv" ]; then
	python3 -m venv venv
	. venv/bin/activate
	echo "Virtual environment created."
	# Install the local monarch module (assuming it's in the current directory)
	pip install monarch

	# Install all dependencies from requirements.txt
	pip install -r requirements.txt
else
	echo "Virtual environment already exists."
	. venv/bin/activate
fi

# Activate the virtual environment
echo "Activating virtual environment..."

# Keep the shell running so you stay in the virtual environment
echo "Virtual environment setup is complete, dependencies installed."
echo "You are now inside the virtual environment."

python3 -m monarch repl
