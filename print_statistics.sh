#!/bin/bash

# This file is not in the shell folder since it is easier if it is in the root folder
# of the git repository.

clear

# Remove all the qlog files to not distort the statistics
sudo find ./src -name "*.qlog" -type f -delete

# Function to count lines of code for a given file extension
count_lines() {
  local ext=$1
  find ./src -name "*.$ext" -type f -exec cat {} + | wc -l
}

# Print repository information
echo "\n"
echo "File Information"
echo "----------------------"

# Total lines of code for each language
echo "Lines of code for Go files (.go): $(count_lines "go")"
echo "Lines of code for C files (.c): $(count_lines "c")"
echo "Lines of code for Shell scripts (.sh): $(count_lines "sh")"
echo "Lines of code for Text files (.txt): $(count_lines "txt")"
echo "Lines of code for Makefiles (Makefile): $(find ./src -name 'Makefile' -type f -exec cat {} + | wc -l)"

# General git repository information
if [ -d .git ]; then
  echo "\n"
  echo "Git Information"
  echo "--------------------------"
  echo "Number of commits: $(git rev-list --all --count)"
  echo "Number of branches: $(git branch -r | wc -l)"
  echo "Number of tags: $(git tag -l | wc -l)"

  echo
  echo "Most recent commit:"
  git log -1 --format="%h - %s (%ci) <%an>"
  # Get the latest commit date
  latest_commit_date=$(git log -1 --format=%cd --date=short)
  # Calculate the days since the latest commit
  days_since_commit=$(( ($(date -u +%s) - $(date -ud "$latest_commit_date" +%s)) / 86400 ))
  echo "Days since last commit: $days_since_commit"
  
  echo 
  echo "Earliest commit:"
  git log --reverse --format="%h - %s (%ci) <%an>" | head -1
  # Get the date of the first commit
  first_commit_date=$(git log --reverse --format=%cd --date=short | head -n 1)
  # Calculate the days since the first commit
  days_since_first_commit=$(( ($(date -u +%s) - $(date -ud "$first_commit_date" +%s)) / 86400 ))
  echo "Days since first commit: $days_since_first_commit"

else
  echo "Not a git repository."
fi

# Additional interesting information
echo "\n"
echo "Additional Information"
echo "----------------------"
echo "Total number of files: $(find ./src -type f | wc -l)"
echo "Total number of directories: $(find ./src -type d | wc -l)"
echo "Disk usage: $(du -sh . | cut -f1)"
echo
