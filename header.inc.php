<head>
    <meta charset="utf-8">
    <title><?=$ServiceName?></title>

    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="">
    <meta name="keywords" content="">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <meta name="format-detection" content="telephone=no,email=no,address=no">
    <link rel="canonical" href="">
    <link rel="icon" href="favicon.ico">
    <link rel="apple-touch-icon" href="icon.png">

    <!-- OGP -->
    <meta property="og:url" content="">
    <meta property="og:type" content="">
    <meta property="og:title" content="">
    <meta property="og:description" content="">
    <meta property="og:site_name" content="">
    <meta property="og:image" content="">
    <meta property="og:locale" content="ja_JP">

    <!-- Import Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&display=swap" rel="stylesheet">

    <!-- Import CSS -->
    <link rel="stylesheet" href="/common/css/reset.css">
    <link rel="stylesheet" href="/common/css/style.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">

    <!-- Import JS/jQuery Library -->
    <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
    <style>
        body {
            padding-top: 80px;
            background-color: lightgray;
        }

        /* ファイル添付部分の見た目*/
        #attachment label {
            display: inline-block;
            position: relative;
            background: #666;
            color: #fff;
            font-size: 16px;
            padding: 10px 18px;
            border-radius: 4px;
            transition: all 0.3s;
        }
        #attachment label input {
            position: absolute;
            left: 0;
            top: 0;
            opacity: 0;
            width: 100%;
            height: 100%;
        }

    </style>
</head>