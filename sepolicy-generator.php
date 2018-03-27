<?php
$seuname;
$seuname_is_valid;
$seprogname;
$seprogname_is_valid;
$filename;
echo "SELINUX Policy Gener8tor\r\n";
echo "Made by hufan-b & bencejuhaasz\r\n";
echo "Please provide following variables:\r\n";
do {
    $seuname = readline("1) SELinux User Name (must exist!): ");
    if(preg_match('/^[a-z0-9]+$/', $seuname)) {
	$seuname_is_valid = "DA";
    } else {
	$seuname_is_valid = "NIET";
	echo "Not valid name (must contain lower-case letters only). Enter it again\r\n";
    }
} while ($seuname_is_valid == "NIET");
echo "Passed validation check\r\n";

do {
    $seprogname = readline("2) Application name: ");
    if(preg_match('/^[a-z0-9]+$/', $seprogname)) {
	$seprogname_is_valid = "DA";
    } else {
	$seprogname_is_valid = "NIET";
	echo "Not valid name (must contain lower-case letters only). Enter it again\r\n";
    }
} while ($seprogname_is_valid == "NIET");
echo "Passed validation check\r\n";

$filecontent = <<<EOT
policy_module({$seprogname},1.0.0)

require {
	#user
	type {$seuname}_t;
	role {$seuname}_r;
	type {$seuname}_t;
	#socket
	class unix_stream_socket connectto;
	type pulseaudio_home_t;
        type sound_device_t;
	type pulseaudio_exec_t;
	class netlink_kobject_uevent_socket { bind create getattr setopt };
        class unix_dgram_socket { connect create };
	#tmp
	type tmpfs_t;
	type tmp_t;
	#proc
	type proc_t;
	#file
	class file { execute execute_no_trans getattr lock map open read write };
	attribute file_type;
	#process
	class process { execmem setcap setrlimit setsched };

}
#app_t
type {$seprogname}_t;

#file_t
type {$seprogname}_exec_t;
type {$seprogname}_file_t;

typeattribute {$seprogname}_file_t file_type;
typeattribute {$seprogname}_exec_t file_type;

#domain
application_domain({$seprogname}_t, {$seprogname}_exec_t)
domtrans_pattern({$seuname}_t, {$seprogname}_exec_t, {$seprogname}_t)

#permissive {$seprogname}_t;

#role
role {$seuname}_r types {{$seprogname}_t {$seprogname}_file_t {$seprogname}_exec_t};


alsa_read_rw_config({$seprogname}_t)

#allow {$seuname}_t
allow {$seuname}_t {$seprogname}_file_t:dir {relabelfrom relabelto};
allow {$seuname}_t {$seprogname}_file_t:file {relabelfrom relabelto};
allow {$seuname}_t {$seprogname}_exec_t:file {relabelfrom relabelto};

allow {$seuname}_t {$seprogname}_file_t:file {getattr read open write};
allow {$seuname}_t {$seprogname}_file_t:dir {getattr search read open write add_name remove_name create rename};
allow {$seuname}_t {$seprogname}_exec_t:file {execute read open};


#allow {$seprogname}_t
allow {$seprogname}_t {$seuname}_t:unix_stream_socket connectto;
allow {$seprogname}_t self:unix_dgram_socket { connect create };

allow {$seprogname}_t {$seprogname}_file_t:dir { open read getattr search write add_name remove_name create rename};
allow {$seprogname}_t {$seprogname}_file_t:file { getattr open read execute map write create rename unlink};

allow {$seprogname}_t tmpfs_t:file { map read write };
allow {$seprogname}_t tmp_t:file {create write open read};
allow {$seprogname}_t proc_t:file { getattr open read };

allow {$seprogname}_t self:netlink_kobject_uevent_socket { bind create getattr setopt };
allow {$seprogname}_t self:process { setcap setrlimit setsched  execmem};

#tmp
fs_list_tmpfs({$seprogname}_t)
#files_manage_generic_tmp_dirs({$seprogname}_t)
fs_getattr_tmpfs({$seprogname}_t)
#userdom_manage_tmp_dirs({$seprogname}_t)
#userdom_manage_tmp_files({$seprogname}_t)
fs_rw_inherited_tmpfs_files({$seuname}_t)

#socket
dbus_stream_connect_system_dbusd({$seprogname}_t)
fs_read_cgroup_files({$seprogname}_t)
userdom_stream_connect({$seprogname}_t)

#dev
dev_list_sysfs({$seprogname}_t)
dev_read_sysfs({$seprogname}_t)
dev_rw_dri({$seprogname}_t)
logging_create_devlog_dev({$seprogname}_t)
udev_read_db({$seprogname}_t)

#kernel
kernel_dgram_send({$seprogname}_t)
kernel_read_vm_sysctls({$seprogname}_t)

#x
xserver_manage_user_xauth({$seprogname}_t)

#alsa
pulseaudio_stream_connect({$seprogname}_t)


#user
userdom_mmap_user_home_content_files({$seprogname}_t)
userdom_use_inherited_user_ptys({$seprogname}_t)


EOT;

$filename = readline("3) Provide a file name to save to: ");
//echo $filecontent;
file_put_contents($filename, $filecontent, LOCK_EX);
?>