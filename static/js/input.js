function showFileName() {
    var fileInput = document.getElementById('fileInput');
    var fileName = document.getElementById('fileName');
    
    if (fileInput.files.length > 0) {
        fileName.textContent = fileInput.files[0].name;
    } else {
        fileName.textContent = "選択されていません";
    }
}