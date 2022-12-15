$(function () {
    bsCustomFileInput.init()
    $('[data-toggle="tooltip"]').tooltip()
    $('#menu-tabs a').on('click', function (e) {
        e.preventDefault()
        $(this).tab('show')
    })
    $('#menu-tabs a[href="#fingerprints"]').tab('show')
    $('#file_upload_selector').change(function () {
        const upload_btn = $('#upload_btn')
        const show_report_btn = $('#show_report_btn')
        upload_btn.hide()
        show_report_btn.hide()
        hashfile(this, upload_btn, show_report_btn)
    })
})


function hashfile(file_selector, upload_btn, report_btn) {
    return readbinaryfile(file_selector.files[0])
        .then(function (result) {
            result = new Uint8Array(result);
            return crypto.subtle.digest('SHA-256', result);
        }).then(function (result) {
            result = new Uint8Array(result);
            const hash = Uint8ArrayToHexString(result);
            $.ajax(`/api/exists/${hash}`).done(function (data){
                if(data.ret_code == 0){
                    report_btn.attr('href', data.report_url)
                    report_btn.show()
                } else {
                    upload_btn.show()
                }
            })
        });
}

function readbinaryfile(file) {
    return new Promise((resolve, reject) => {
        var fr = new FileReader();
        fr.onload = () => {
            resolve(fr.result)
        };
        fr.readAsArrayBuffer(file);
    });
}

function Uint8ArrayToHexString(ui8array) {
    var hexstring = '',
        h;
    for (var i = 0; i < ui8array.length; i++) {
        h = ui8array[i].toString(16);
        if (h.length == 1) {
            h = '0' + h;
        }
        hexstring += h;
    }
    var p = Math.pow(2, Math.ceil(Math.log2(hexstring.length)));
    hexstring = hexstring.padStart(p, '0');
    return hexstring;
}

