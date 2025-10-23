#!/bin/bash
# Demo script for VT-KeyRotator
# This demonstrates how to use the tool without real API keys

echo "VT-KeyRotator Demo"
echo "=================="
echo ""

echo "1. Setting up configuration..."
cp config.json.example config.json
echo "   ✓ Created config.json from example"
echo ""

echo "2. Creating sample IP list..."
cp ips.txt.example ips.txt
echo "   ✓ Created ips.txt with sample IPs"
echo ""

echo "3. Checking help message..."
python3 vt_keyrotator.py --help
echo ""

echo "4. Demo complete!"
echo ""
echo "To use with real API keys:"
echo "  1. Get your API key from https://www.virustotal.com/gui/my-apikey"
echo "  2. Edit config.json and add your API key(s)"
echo "  3. Run: python3 vt_keyrotator.py --input ips.txt --output results.csv"
echo ""
echo "Note: This demo uses placeholder API keys and won't actually scan IPs."
echo "      Replace them with real keys to perform actual scans."
