<?php
// SPDX-License-Identifier: PMPL-1.0-or-later
// Test fixture: WordPress security issues

// Missing nonce verification
function handle_form_submission() {
    if ($_POST['action'] == 'save_settings') {
        update_option('my_setting', $_POST['value']);
    }
}

// Missing capability check
function admin_delete_user() {
    $user_id = $_GET['user_id'];
    wp_delete_user($user_id);
}

// Unsafe AJAX handler
add_action('wp_ajax_update_post', 'update_post_ajax');
function update_post_ajax() {
    $post_id = $_POST['post_id'];
    wp_update_post(array(
        'ID' => $post_id,
        'post_content' => $_POST['content']
    ));
}

// Missing sanitization
function display_user_data() {
    $user_name = $_GET['name'];
    echo "<h1>User: $user_name</h1>";
}
