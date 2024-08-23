<!DOCTYPE html>
<html lang="ja">
<?php include('header.inc.html'); ?>

<body>
    <?php require_once 'nav.tpl.html'; ?>
    <!-- START Main Area -->
    <main>
        <div class="container">
            <form action="result.php" method="post">
                <div class="form-group">
                    <label for="comment_1">URL</label>
                    <input type="text" class="form-control" name="URL" id="URL_1">
                </div>
                <button type="submit">送信</button>
            </form>
        </div>
    </main>
    <!-- END Main Area -->
    <?php include('footer.inc.html'); ?>
</body>

</html>