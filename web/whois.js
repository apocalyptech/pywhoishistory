
function submitWhois() {
    document.getElementById("whoisform").submit();
    return true;
}

function showRawData(name) {
    show_link = document.getElementById("show_raw_link_" + name);
    hide_link = document.getElementById("hide_raw_link_" + name);
    data = document.getElementById("raw_data_" + name);
    show_link.style.display = 'none';
    hide_link.style.display = 'inline';
    data.style.display = 'inline-block';
}

function hideRawData(name) {
    show_link = document.getElementById("show_raw_link_" + name);
    hide_link = document.getElementById("hide_raw_link_" + name);
    data = document.getElementById("raw_data_" + name);
    show_link.style.display = 'inline';
    hide_link.style.display = 'none';
    data.style.display = 'none';
}

