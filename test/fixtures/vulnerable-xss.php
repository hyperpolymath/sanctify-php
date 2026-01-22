<?php
// SPDX-License-Identifier: PMPL-1.0-or-later
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
