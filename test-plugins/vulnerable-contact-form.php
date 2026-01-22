<?php
/**
 * Plugin Name: Vulnerable Contact Form
 * Description: Simplified example with security issues
 * Version: 1.0.0
 * SPDX-License-Identifier: PMPL-1.0-or-later
 */

// Missing ABSPATH check

// AJAX handler for form submission - VULNERABLE
add_action('wp_ajax_submit_contact_form', 'handle_contact_form');
add_action('wp_ajax_nopriv_submit_contact_form', 'handle_contact_form');

function handle_contact_form() {
    // No nonce verification
    // No capability check

    global $wpdb;

    // SQL injection vulnerability
    $name = $_POST['name'];
    $email = $_POST['email'];
    $message = $_POST['message'];

    $sql = "INSERT INTO {$wpdb->prefix}contact_forms (name, email, message)
            VALUES ('$name', '$email', '$message')";
    $wpdb->query($sql);

    // Send email with XSS vulnerability in admin notification
    $admin_email = get_option('admin_email');
    $subject = "New contact form submission from " . $_POST['name'];
    $body = "Name: " . $_POST['name'] . "\n";
    $body .= "Email: " . $_POST['email'] . "\n";
    $body .= "Message: " . $_POST['message'];

    wp_mail($admin_email, $subject, $body);

    echo "Form submitted successfully!";
    exit;
}

// Admin page to view submissions - VULNERABLE
add_action('admin_menu', 'add_contact_form_menu');

function add_contact_form_menu() {
    add_menu_page(
        'Contact Forms',
        'Contact Forms',
        'read', // Too permissive capability
        'contact-forms',
        'display_contact_forms'
    );
}

function display_contact_forms() {
    global $wpdb;

    // No capability check

    // Delete functionality without nonce
    if (isset($_GET['delete_id'])) {
        $id = $_GET['delete_id'];
        $wpdb->query("DELETE FROM {$wpdb->prefix}contact_forms WHERE id = $id");
    }

    // XSS vulnerability in output
    $results = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}contact_forms ORDER BY id DESC");

    echo "<h1>Contact Form Submissions</h1>";
    echo "<table>";
    echo "<tr><th>Name</th><th>Email</th><th>Message</th><th>Actions</th></tr>";

    foreach ($results as $row) {
        echo "<tr>";
        echo "<td>" . $row->name . "</td>"; // XSS
        echo "<td>" . $row->email . "</td>"; // XSS
        echo "<td>" . $row->message . "</td>"; // XSS
        echo "<td><a href='?page=contact-forms&delete_id=" . $row->id . "'>Delete</a></td>"; // CSRF
        echo "</tr>";
    }

    echo "</table>";
}

// File upload functionality - VULNERABLE
add_action('wp_ajax_upload_attachment', 'handle_file_upload');

function handle_file_upload() {
    // No nonce, no capability check

    $upload_dir = wp_upload_dir();
    $target = $upload_dir['basedir'] . '/' . $_FILES['file']['name']; // Path traversal

    // No file type validation
    move_uploaded_file($_FILES['file']['tmp_name'], $target);

    echo json_encode(['success' => true, 'file' => $_FILES['file']['name']]);
    exit;
}

// Settings page - VULNERABLE
add_action('admin_init', 'register_contact_form_settings');

function register_contact_form_settings() {
    // Saving settings without nonce
    if (isset($_POST['contact_form_settings'])) {
        // No capability check
        // No sanitization
        update_option('contact_form_email', $_POST['admin_email']);
        update_option('contact_form_subject', $_POST['email_subject']);
        update_option('contact_form_redirect', $_POST['redirect_url']);
    }
}

// Shortcode with XSS
add_shortcode('contact_form', 'render_contact_form');

function render_contact_form($atts) {
    $atts = shortcode_atts([
        'recipient' => get_option('admin_email'),
        'title' => 'Contact Us'
    ], $atts);

    $output = "<h2>" . $atts['title'] . "</h2>"; // XSS from shortcode attribute
    $output .= "<form id='contact-form'>";
    $output .= "<input type='text' name='name' placeholder='Name' required>";
    $output .= "<input type='email' name='email' placeholder='Email' required>";
    $output .= "<textarea name='message' placeholder='Message' required></textarea>";
    $output .= "<button type='submit'>Submit</button>";
    $output .= "</form>";

    return $output;
}
