sed -i '' 's/\"/\\"/g' $1
sed -i '' s/\'/\"/g $1
sed -i '' 's/: True/: true/g' $1
sed -i '' 's/: False/: false/g' $1
sed -i '' 's/: None/: null/g' $1