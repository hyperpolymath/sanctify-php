<?php
// SPDX-License-Identifier: MPL-2.0
// Test fixture: XSS vulnerabilities

function display_welcome() {
    echo "Welcome, " . $_GET['name'] . "!";
}

function show_comment($comment) {
    echo "<div class='comment'>" . $_POST['comment'] . "</div>";
}

function render_attribute() {
    echo "<input type='text' value='" . $_GET['value'] . "'>";
}
