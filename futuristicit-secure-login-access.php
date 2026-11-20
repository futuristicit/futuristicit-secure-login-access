<?php
/**
 * Plugin Name: FuturisticIT Secure Login Access
 * Description: Changes the WordPress login logo and hides wp-login.php behind a custom login endpoint.
 * Plugin URI: https://futuristicit.com
 * Version: 1.0.3
 * Author: FuturisticIT
 * License: GPL-2.0-or-later
 * Text Domain: futuristicit-secure-login-access
 * Requires at least: 5.6
 * Tested up to: 7.1
 * Requires PHP: 7.4
 * 
 * License: GNU General Public License v3.0
 * License URI: http://www.gnu.org/licenses/gpl-3.0.html
 */

if (!defined('ABSPATH')) {
    exit;
}

final class FSCL_Secure_Custom_Login
{
    private const VERSION = '1.0.0';
    private const OPTION_NAME = 'fscl_secure_custom_login_options';
    private const ACCESS_KEY = 'fscl_login_access';
    private const NONCE_ACTION = 'fscl_login_access';
    private const DEFAULT_LOGIN_SLUG = 'secure-login';

    public static function init(): void
    {
        add_action('init', [__CLASS__, 'add_rewrite_rule']);
        add_action('template_redirect', [__CLASS__, 'handle_custom_login_endpoint']);
        add_action('login_init', [__CLASS__, 'block_direct_wp_login']);
        add_action('login_enqueue_scripts', [__CLASS__, 'customize_login_logo']);
        add_filter('login_headerurl', [__CLASS__, 'login_logo_url']);
        add_filter('login_headertext', [__CLASS__, 'login_logo_text']);
        add_action('wp_logout', [__CLASS__, 'clear_login_access_cookie']);

        if (is_admin()) {
            add_action('admin_menu', [__CLASS__, 'add_settings_page']);
            add_action('admin_init', [__CLASS__, 'register_settings']);
            add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_admin_assets']);
            add_filter('plugin_action_links_' . plugin_basename(__FILE__), [__CLASS__, 'add_settings_link']);
            add_action('update_option_' . self::OPTION_NAME, [__CLASS__, 'maybe_flush_rewrite_rules'], 10, 2);
        }

        register_activation_hook(__FILE__, [__CLASS__, 'activate']);
        register_deactivation_hook(__FILE__, [__CLASS__, 'deactivate']);
    }

    public static function activate(): void
    {
        if (!get_option(self::OPTION_NAME)) {
            add_option(self::OPTION_NAME, self::default_options());
        }

        self::add_rewrite_rule();
        flush_rewrite_rules();
    }

    public static function deactivate(): void
    {
        flush_rewrite_rules();
        self::clear_login_access_cookie();
    }

    public static function add_rewrite_rule(): void
    {
        add_rewrite_tag('%fscl_custom_login%', '1');
        add_rewrite_rule('^' . preg_quote(self::login_slug(), '/') . '/?$', 'index.php?fscl_custom_login=1', 'top');
    }

    public static function handle_custom_login_endpoint(): void
    {
        if (get_query_var('fscl_custom_login') !== '1') {
            return;
        }

        self::grant_login_access();

        $login_url = add_query_arg(
            [
                self::ACCESS_KEY => wp_create_nonce(self::NONCE_ACTION),
            ],
            wp_login_url()
        );

        wp_safe_redirect($login_url);
        exit;
    }

    public static function block_direct_wp_login(): void
    {
        $method = isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET';

        if ($method === 'POST' && self::has_login_cookie()) {
            return;
        }

        if ($method === 'GET' && self::has_login_nonce()) {
            return;
        }

        wp_safe_redirect(self::redirect_url());
        exit;
    }

    public static function customize_login_logo(): void
    {
        $logo_url = self::logo_url();

        if ($logo_url === '') {
            return;
        }

        $css = sprintf(
            '.login h1 a {
                background-image: url(%1$s);
                background-size: contain;
                background-position: center;
                width: 100%%;
                max-width: 320px;
                height: 100px;
            }',
            esc_url($logo_url)
        );

        wp_add_inline_style('login', $css);
    }

    public static function login_logo_url(): string
    {
        return home_url('/');
    }

    public static function login_logo_text(): string
    {
        return get_bloginfo('name');
    }

    public static function clear_login_access_cookie(): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(self::ACCESS_KEY, '', time() - HOUR_IN_SECONDS, COOKIEPATH ?: '/', COOKIE_DOMAIN, is_ssl(), true);
    }

    public static function add_settings_page(): void
    {
        add_options_page(
            __('Secure Custom Login', 'futuristicit-secure-login-access'),
            __('Secure Login', 'futuristicit-secure-login-access'),
            'manage_options',
            'futuristicit-secure-login-access',
            [__CLASS__, 'render_settings_page']
        );
    }

    public static function register_settings(): void
    {
        register_setting(
            'fscl_secure_custom_login',
            self::OPTION_NAME,
            [
                'sanitize_callback' => [__CLASS__, 'sanitize_options'],
                'default' => self::default_options(),
            ]
        );

        add_settings_section(
            'fscl_main_section',
            __('Login protection', 'futuristicit-secure-login-access'),
            '__return_false',
            'fscl_secure_custom_login'
        );

        add_settings_field(
            'login_slug',
            __('Secret login endpoint', 'futuristicit-secure-login-access'),
            [__CLASS__, 'render_login_slug_field'],
            'fscl_secure_custom_login',
            'fscl_main_section'
        );

        add_settings_field(
            'logo_attachment_id',
            __('Login logo', 'futuristicit-secure-login-access'),
            [__CLASS__, 'render_logo_upload_field'],
            'fscl_secure_custom_login',
            'fscl_main_section'
        );

        add_settings_field(
            'redirect_url',
            __('Blocked login redirect URL', 'futuristicit-secure-login-access'),
            [__CLASS__, 'render_redirect_url_field'],
            'fscl_secure_custom_login',
            'fscl_main_section'
        );
    }

    public static function sanitize_options(array $input): array
    {
        $defaults = self::default_options();

        $slug = isset($input['login_slug']) ? sanitize_title($input['login_slug']) : $defaults['login_slug'];
        $logo_attachment_id = isset($input['logo_attachment_id']) ? absint($input['logo_attachment_id']) : 0;
        $redirect_url = isset($input['redirect_url']) ? esc_url_raw(trim((string) $input['redirect_url'])) : '';

        return [
            'login_slug' => $slug !== '' ? $slug : $defaults['login_slug'],
            'logo_attachment_id' => $logo_attachment_id,
            'redirect_url' => $redirect_url !== '' ? $redirect_url : home_url('/'),
        ];
    }

    public static function enqueue_admin_assets(string $hook): void
    {
        if ($hook !== 'settings_page_futuristicit-secure-login-access') {
            return;
        }

        wp_enqueue_media();
        wp_enqueue_script('jquery');

        $script = "
            jQuery(function($) {
                var frame;

                $('#fscl-upload-logo').on('click', function(event) {
                    event.preventDefault();

                    if (frame) {
                        frame.open();
                        return;
                    }

                    frame = wp.media({
                        title: 'Choose login logo',
                        button: { text: 'Use this logo' },
                        multiple: false,
                        library: { type: 'image' }
                    });

                    frame.on('select', function() {
                        var attachment = frame.state().get('selection').first().toJSON();
                        $('#fscl-logo-attachment-id').val(attachment.id);
                        $('#fscl-logo-preview').attr('src', attachment.url).show();
                        $('#fscl-remove-logo').show();
                    });

                    frame.open();
                });

                $('#fscl-remove-logo').on('click', function(event) {
                    event.preventDefault();
                    $('#fscl-logo-attachment-id').val('0');
                    $('#fscl-logo-preview').attr('src', '').hide();
                    $(this).hide();
                });
            });
        ";

        wp_add_inline_script('jquery', $script);
    }

    public static function render_settings_page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $login_url = home_url('/' . self::login_slug() . '/');
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Secure Custom Login', 'futuristicit-secure-login-access'); ?></h1>
            <p>
                <?php esc_html_e('Use this URL for WordPress login:', 'futuristicit-secure-login-access'); ?>
                <strong><a href="<?php echo esc_url($login_url); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html($login_url); ?></a></strong>
            </p>
            <form method="post" action="options.php">
                <?php
                settings_fields('fscl_secure_custom_login');
                do_settings_sections('fscl_secure_custom_login');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }

    public static function render_login_slug_field(): void
    {
        $options = self::options();
        ?>
        <input type="text" class="regular-text" name="<?php echo esc_attr(self::OPTION_NAME); ?>[login_slug]" value="<?php echo esc_attr($options['login_slug']); ?>" />
        <p class="description"><?php esc_html_e('Example: my-secret-login. Direct wp-login.php visits will still be blocked.', 'futuristicit-secure-login-access'); ?></p>
        <?php
    }

    public static function render_logo_upload_field(): void
    {
        $options = self::options();
        $attachment_id = absint($options['logo_attachment_id']);
        $logo_url = $attachment_id > 0 ? wp_get_attachment_image_url($attachment_id, 'medium') : '';
        ?>
        <input type="hidden" id="fscl-logo-attachment-id" name="<?php echo esc_attr(self::OPTION_NAME); ?>[logo_attachment_id]" value="<?php echo esc_attr((string) $attachment_id); ?>" />
        <div style="margin-bottom: 10px;">
            <img id="fscl-logo-preview" src="<?php echo esc_url($logo_url); ?>" alt="" style="<?php echo $logo_url ? '' : 'display:none;'; ?>max-width: 220px; max-height: 120px; height: auto; background: #fff; border: 1px solid #ccd0d4; padding: 8px;" />
        </div>
        <button type="button" class="button" id="fscl-upload-logo"><?php esc_html_e('Upload / Choose Logo', 'futuristicit-secure-login-access'); ?></button>
        <button type="button" class="button" id="fscl-remove-logo" style="<?php echo $logo_url ? '' : 'display:none;'; ?>"><?php esc_html_e('Remove Logo', 'futuristicit-secure-login-access'); ?></button>
        <p class="description"><?php esc_html_e('Choose an image from the Media Library or upload a new one.', 'futuristicit-secure-login-access'); ?></p>
        <?php
    }

    public static function render_redirect_url_field(): void
    {
        $options = self::options();
        ?>
        <input type="url" class="regular-text" name="<?php echo esc_attr(self::OPTION_NAME); ?>[redirect_url]" value="<?php echo esc_url($options['redirect_url']); ?>" />
        <p class="description"><?php esc_html_e('Visitors who open wp-login.php directly are sent here.', 'futuristicit-secure-login-access'); ?></p>
        <?php
    }

    public static function add_settings_link(array $links): array
    {
        $settings_link = sprintf(
            '<a href="%s">%s</a>',
            esc_url(admin_url('options-general.php?page=secure-custom-login')),
            esc_html__('Settings', 'futuristicit-secure-login-access')
        );

        array_unshift($links, $settings_link);
        return $links;
    }

    public static function maybe_flush_rewrite_rules(array $old_options, array $new_options): void
    {
        if (($old_options['login_slug'] ?? '') !== ($new_options['login_slug'] ?? '')) {
            self::clear_login_access_cookie();
            self::add_rewrite_rule();
            flush_rewrite_rules();
        }
    }

    private static function grant_login_access(): void
    {
        if (headers_sent()) {
            return;
        }

        setcookie(self::ACCESS_KEY, '1', time() + 10 * MINUTE_IN_SECONDS, COOKIEPATH ?: '/', COOKIE_DOMAIN, is_ssl(), true);
    }

    private static function has_login_nonce(): bool
    {
        $key = self::ACCESS_KEY;

        return isset($_GET[$key]) && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET[$key])), self::NONCE_ACTION);
    }

    private static function has_login_cookie(): bool
    {
        $key = self::ACCESS_KEY;

        return isset($_COOKIE[$key]) && $_COOKIE[$key] === '1';
    }

    private static function login_slug(): string
    {
        $options = self::options();
        return $options['login_slug'];
    }

    private static function logo_url(): string
    {
        $options = self::options();
        $attachment_id = absint($options['logo_attachment_id']);

        if ($attachment_id <= 0) {
            return '';
        }

        $url = wp_get_attachment_image_url($attachment_id, 'full');
        return $url ? esc_url_raw($url) : '';
    }

    private static function redirect_url(): string
    {
        $options = self::options();
        return $options['redirect_url'];
    }

    private static function options(): array
    {
        return wp_parse_args((array) get_option(self::OPTION_NAME, []), self::default_options());
    }

    private static function default_options(): array
    {
        return [
            'login_slug' => self::DEFAULT_LOGIN_SLUG,
            'logo_attachment_id' => 0,
            'redirect_url' => home_url('/'),
        ];
    }
}

FSCL_Secure_Custom_Login::init();

