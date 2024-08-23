<!DOCTYPE html>
<html lang="ja">
<?php $ServiceName = "サービス名" ?>
<?php include('header.inc.php'); ?>

<body>
    <?php require_once 'nav.tpl.php'; ?>
    <!-- START Main Area -->
    <main>
        <div class="container">
            <h1 style="color:#BBBBFF"><?= $ServiceName ?></h1>
            <form action="result.php" method="post">
                <div class="form-group">
                    <label for="comment_1">URL</label>
                    <input type="text" class="form-control" name="URL">
                    <br>
                    <div id="attachment">
                        <label><input type="file" class="fileinput" name="FILE">ファイルを添付する</label>
                    </div>
                </div>
                <button type="submit">送信</button>
            </form>
        </div>
    </main>
    <!-- END Main Area -->
    <?php include('footer.inc.php'); ?>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
</body>

</html>