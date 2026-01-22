<?php
/**
 * Plugin Name: Secure Contact Form
 * Description: Properly secured example
 * Version: 1.0.0
 * SPDX-License-Identifier: PMPL-1.0-or-later
 */

declare(strict_types=1);

// Proper ABSPATH check
if (!defined('ABSPATH')) {
    exit;
}

// AJAX handler with proper security
add_action('wp_ajax_submit_contact_form', 'handle_contact_form');
add_action('wp_ajax_nopriv_submit_contact_form', 'handle_contact_form');

function handle_contact_form(): void {
    // Verify nonce
    check_ajax_referer('contact_form_nonce', 'nonce');

    // Rate limiting check (stored in transient)
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $rate_key = 'contact_form_rate_' . md5($ip);
    $submissions = (int) get_transient($rate_key);

    if ($submissions >= 3) {
        wp_send_json_error('Too many submissions. Please try again later.');
        return;
    }

    global $wpdb;

    // Sanitize and validate input
    $name = sanitize_text_field($_POST['name'] ?? '');
    $email = sanitize_email($_POST['email'] ?? '');
    $message = sanitize_textarea_field($_POST['message'] ?? '');

    if (empty($name) || empty($email) || empty($message)) {
        wp_send_json_error('All fields are required.');
        return;
    }

    if (!is_email($email)) {
        wp_send_json_error('Invalid email address.');
        return;
    }

    // Use prepared statement
    $wpdb->insert(
        $wpdb->prefix . 'contact_forms',
        [
            'name' => $name,
            'email' => $email,
            'message' => $message,
            'submitted_at' => current_time('mysql'),
            'ip_address' => $ip
        ],
        ['%s', '%s', '%s', '%s', '%s']
    );

    // Update rate limit
    set_transient($rate_key, $submissions + 1, HOUR_IN_SECONDS);

    // Send email with properly escaped content
    $admin_email = sanitize_email(get_option('admin_email'));
    $subject = sprintf(
        __('New contact form submission from %s', 'contact-form'),
        sanitize_text_field($name)
    );

    $body = sprintf(
        __("Name: %s\nEmail: %s\nMessage: %s", 'contact-form'),
        $name,
        $email,
        $message
    );

    wp_mail($admin_email, $subject, $body);

    wp_send_json_success('Form submitted successfully!');
}

// Admin page with proper security
add_action('admin_menu', 'add_contact_form_menu');

function add_contact_form_menu(): void {
    add_menu_page(
        __('Contact Forms', 'contact-form'),
        __('Contact Forms', 'contact-form'),
        'manage_options', // Proper capability
        'contact-forms',
        'display_contact_forms',
        'dashicons-email'
    );
}

function display_contact_forms(): void {
    // Check capability
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.', 'contact-form'));
    }

    global $wpdb;

    // Handle deletion with nonce
    if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
        check_admin_referer('delete_contact_form_' . $_GET['id']);

        $id = absint($_GET['id']);
        $wpdb->delete(
            $wpdb->prefix . 'contact_forms',
            ['id' => $id],
            ['%d']
        );

        echo '<div class="notice notice-success"><p>' .
            esc_html__('Submission deleted.', 'contact-form') .
            '</p></div>';
    }

    // Fetch results with prepared statement
    $results = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}contact_forms ORDER BY id DESC LIMIT %d",
            100
        )
    );

    echo '<div class="wrap">';
    echo '<h1>' . esc_html__('Contact Form Submissions', 'contact-form') . '</h1>';
    echo '<table class="wp-list-table widefat fixed striped">';
    echo '<thead><tr>';
    echo '<th>' . esc_html__('Name', 'contact-form') . '</th>';
    echo '<th>' . esc_html__('Email', 'contact-form') . '</th>';
    echo '<th>' . esc_html__('Message', 'contact-form') . '</th>';
    echo '<th>' . esc_html__('Date', 'contact-form') . '</th>';
    echo '<th>' . esc_html__('Actions', 'contact-form') . '</th>';
    echo '</tr></thead><tbody>';

    foreach ($results as $row) {
        $delete_url = wp_nonce_url(
            admin_url('admin.php?page=contact-forms&action=delete&id=' . $row->id),
            'delete_contact_form_' . $row->id
        );

        echo '<tr>';
        echo '<td>' . esc_html($row->name) . '</td>';
        echo '<td>' . esc_html($row->email) . '</td>';
        echo '<td>' . esc_html(wp_trim_words($row->message, 10)) . '</td>';
        echo '<td>' . esc_html($row->submitted_at) . '</td>';
        echo '<td><a href="' . esc_url($delete_url) . '" class="button">' .
            esc_html__('Delete', 'contact-form') . '</a></td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
    echo '</div>';
}

// File upload with proper validation
add_action('wp_ajax_upload_attachment', 'handle_file_upload');

function handle_file_upload(): void {
    // Verify nonce and capability
    check_ajax_referer('upload_attachment_nonce', 'nonce');

    if (!current_user_can('upload_files')) {
        wp_send_json_error('Insufficient permissions.');
        return;
    }

    // Use WordPress upload handler with file type restrictions
    $uploaded = wp_handle_upload($_FILES['file'], [
        'test_form' => false,
        'mimes' => [
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png'  => 'image/png',
            'pdf'  => 'application/pdf'
        ]
    ]);

    if (isset($uploaded['error'])) {
        wp_send_json_error($uploaded['error']);
        return;
    }

    wp_send_json_success([
        'file' => basename($uploaded['file']),
        'url' => $uploaded['url']
    ]);
}

// Settings with proper security
add_action('admin_init', 'register_contact_form_settings');

function register_contact_form_settings(): void {
    register_setting(
        'contact_form_settings',
        'contact_form_email',
        [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_email',
            'default' => get_option('admin_email')
        ]
    );

    register_setting(
        'contact_form_settings',
        'contact_form_subject',
        [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => __('New Contact Form Submission', 'contact-form')
        ]
    );

    register_setting(
        'contact_form_settings',
        'contact_form_redirect',
        [
            'type' => 'string',
            'sanitize_callback' => 'esc_url_raw'
        ]
    );
}

// Shortcode with proper escaping
add_shortcode('contact_form', 'render_contact_form');

function render_contact_form(array $atts): string {
    $atts = shortcode_atts([
        'recipient' => get_option('admin_email'),
        'title' => __('Contact Us', 'contact-form')
    ], $atts);

    $nonce = wp_create_nonce('contact_form_nonce');

    $output = '<div class="contact-form-wrapper">';
    $output .= '<h2>' . esc_html($atts['title']) . '</h2>';
    $output .= '<form id="contact-form" data-nonce="' . esc_attr($nonce) . '">';
    $output .= '<input type="text" name="name" placeholder="' .
        esc_attr__('Name', 'contact-form') . '" required>';
    $output .= '<input type="email" name="email" placeholder="' .
        esc_attr__('Email', 'contact-form') . '" required>';
    $output .= '<textarea name="message" placeholder="' .
        esc_attr__('Message', 'contact-form') . '" required></textarea>';
    $output .= '<button type="submit">' .
        esc_html__('Submit', 'contact-form') . '</button>';
    $output .= '</form>';
    $output .= '</div>';

    return $output;
}
