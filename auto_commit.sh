read -p "Commit message: " msg
git add .
git commit -m "$msg"
git push origin master
