$(function () {
    bsCustomFileInput.init()
    $('[data-toggle="tooltip"]').tooltip()
    $('#menu-tabs a').on('click', function (e) {
        e.preventDefault()
        $(this).tab('show')
    })
    $('#menu-tabs a[href="#fingerprints"]').tab('show')
})

