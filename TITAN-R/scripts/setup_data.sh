#!/bin/bash
ZIP_PATH="$1"
if [ -f "$ZIP_PATH" ]; then
    unzip -j "$ZIP_PATH" "KDDTrain+.txt" -d TITAN-R/data/
    unzip -j "$ZIP_PATH" "KDDTest+.txt" -d TITAN-R/data/
    mv TITAN-R/data/KDDTrain+.txt TITAN-R/data/KDDTrain.csv
    mv TITAN-R/data/KDDTest+.txt TITAN-R/data/KDDTest.csv
    echo "Data successfully extracted and renamed for TITAN-R."
else
    echo "Zip file not found at $ZIP_PATH"
fi
