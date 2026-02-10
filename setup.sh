#!/bin/bash

# Update the system and install required packages
sudo apt-get update && sudo apt-get install -y curl

# Automatically install Ollama
curl -sSfL https://ollama.com/download | sh

# Download the llama3.2 LLM model
ollama pull llama3.2

echo "Setup completed successfully!"