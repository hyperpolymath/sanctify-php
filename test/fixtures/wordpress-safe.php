<?php
// SPDX-License-Identifier: PMPL-1.0-or-later
// Test fixture: Safe WordPress code

declare(strict_types=1);

// Proper nonce verification and capability check
function handle_secure_form() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    if (!wp_verify_nonce($_POST['_nonce'], 'my_action')) {
        wp_die('Invalid nonce');
    }

    $value = sanitize_text_field($_POST['value']);
    update_option('my_setting', $value);
}

// Safe database query with prepare
function get_user_posts($user_id) {
    global $wpdb;
    $user_id = absint($user_id);
    $query = $wpdb->prepare(
        "SELECT * FROM {$wpdb->posts} WHERE post_author = %d",
        $user_id
    );
    return $wpdb->get_results($query);
}

// Properly escaped output
function display_user_profile($user) {
    $name = esc_html($user->display_name);
    $bio = wp_kses_post($user->description);
    echo "<h1>{$name}</h1>";
    echo "<div class='bio'>{$bio}</div>";
}

// Safe AJAX handler
add_action('wp_ajax_secure_update', 'secure_update_ajax');
function secure_update_ajax() {
    check_ajax_referer('secure_action', 'nonce');

    if (!current_user_can('edit_posts')) {
        wp_send_json_error('Unauthorized');
    }

    $post_id = absint($_POST['post_id']);
    $content = wp_kses_post($_POST['content']);

    $result = wp_update_post(array(
        'ID' => $post_id,
        'post_content' => $content
    ));

    wp_send_json_success($result);
}
