<?php
/* You can get example at https://github.com/zhifeihuang/ipos
 *
 */
require_once('xssclean.php');

class upload {
public $err = null;

public function load($max_size, $allowed_type, $filed, $dir='./', $is_image=false) {
	if (empty($filename = $this->check($max_size, $allowed_type, $filed))) {
		error_log('load:' . $this->err);
		return false;
	}
	
	$result = array();
	$xss = new xssClean;
	foreach ($filename as $f) {
		if (!($data = @file_get_contents($f['name']))
			|| !$xss->check($data, 0, $is_image)) {
			$result = false;
			$this->err = 'err read file or xss';
			error_log('load:' . $this->err.' data:'.($data ? 'true':'false'));
			break;
		}
		
		$path = md5($data) . '.' . $f['ext'];
		$result[] = $path;
		$path = $dir . $path;
		if (file_exists($path)) continue;
		
		if (!@file_put_contents($path, $data)) {
			$result = false;
			error_log('load: put');
		}
	}
	
	return $result;
}

private function check($max_size, $allowed_type, $field='userfile') {
	if (!isset($_FILES[$field])) {
		$this->err = 'err field:'.$field;
		return false;
	}
	
	$result = array();
	$file = $_FILES[$field];
	if (is_array($file['name'])) {
		$i = 0;
		do {
			if (UPLOAD_ERR_OK != $file['error'][$i] 
				|| filesize($file['tmp_name'][$i]) > $max_size) {
				$this->err = 'err size or load';
				continue;
			}
			
			$finfo = new finfo(FILEINFO_MIME_TYPE);
			if (false === ($ext = array_search($finfo->file($file['tmp_name'][$i]), $allowed_type, true))
				&& $allowed_type != '*') {
				$this->err = 'err type';
				continue;
			}
			
			$result[] = array('name'=>$file['tmp_name'][$i], 'ext'=>$ext);
		} while (++$i < count($file['name']));
	} else {
		if (UPLOAD_ERR_OK != $file['error']
			|| filesize($file['tmp_name']) > $max_size) {
			$this->err = 'err size or load';
			return false;
		}
	
		$finfo = new finfo(FILEINFO_MIME_TYPE);
		if (false === ($ext = array_search($finfo->file($file['tmp_name']), $allowed_type, true))
			&& $allowed_type != '*') {
			$this->err = 'err type';
			return false;
		}
		
		$result[] = array('name'=>$file['tmp_name'], 'ext'=>$ext);
	}
	
	return $result;
}
}
?>