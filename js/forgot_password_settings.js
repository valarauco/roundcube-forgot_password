alteremail_section_select = function(id) {
    if (id) {
        var add_url = '', target = window;
        if (rcmail.env.contentframe && window.frames && window.frames[rcmail.env.contentframe]) {
            add_url = '&_framed=1';
            target = window.frames[rcmail.env.contentframe];
        }
        target.location.href = rcmail.env.comm_path+'&_action=edit-prefs&_section='+id+add_url;
    }
    return true;
};

$(document).ready(function(){

    if (rcmail.gui_objects.sectionslist && (rcmail.env.action == 'alternative_email_preferences')) {
        alteremail_section_select('alternative_email_preferences');
    }
});
