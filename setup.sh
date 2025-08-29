#!/bin/bash
# Setup script for threat intelligence processing

echo "Setting up threat intelligence processing environment..."

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Setup complete!"
echo ""
echo "To use the scripts:"
echo "1. Activate the virtual environment: source .venv/bin/activate"
echo "2. Run the main script: python index.py"
echo "3. Extract indicators: python extract_indicators.py <ndjson_file>"
echo ""
echo "For detailed usage, see README.md"
