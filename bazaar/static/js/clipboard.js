function copyToClipboard(element) {
    try {
        let range = document.createRange();
        range.selectNode(document.getElementById(element));
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
        document.execCommand("copy");
        window.getSelection().removeAllRanges();
    }
    catch (err) {
    }
}