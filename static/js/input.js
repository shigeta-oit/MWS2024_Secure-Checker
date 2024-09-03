$(function () {
    $('input').on('change', function () {
        var file = $(this).prop('files')[0];
        $('.select-image').text(file.name);
    });
});