function forgot_password()
{
	if($('#rcmloginuser').val())
	{
		rcmail.http_post('plugin.forgot_password_reset', "_username=" + escape($('#rcmloginuser').val())+"&_token="+document.form.elements['_token'].value);
	} else {
		rcmail.display_message(rcmail.gettext('forgot_passworduserempty','forgot_password'),'error',10000);
	}
}

$(document).ready(function($) {
	$('#rcmloginpwd').after('<p id="forgot_password"><a class="home" href="javascript:forgot_password();">' + rcmail.gettext('forgotpassword','forgot_password') + '</a></p>');
});
