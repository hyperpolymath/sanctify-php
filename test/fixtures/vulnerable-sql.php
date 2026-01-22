<?php
// SPDX-License-Identifier: PMPL-1.0-or-later
// Test fixture: SQL injection vulnerability

function get_user_by_id($id) {
    global $wpdb;
    $sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
    return $wpdb->query($sql);
}

function unsafe_search($term) {
    global $wpdb;
    $query = "SELECT * FROM posts WHERE title LIKE '%" . $_POST['search'] . "%'";
    return $wpdb->get_results($query);
}
