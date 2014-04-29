rcmail.show_altmail_alert = function (html, title)
{
  var popup = $('<div class="popup">')
    .html(html)
    .dialog({
      title: title,
      modal: true,
      resizable: true,
      width: 500,
      close: function(event, ui) { $(this).remove() },
    });

    // resize and center popup
    var win = $(window), w = win.width(), h = win.height(),
      width = popup.width(), height = popup.height();
    popup.dialog('option', { height: Math.min(h-40, height+70), width: Math.min(w-20, width+50) })
      .dialog('option', 'position', ['center', 'center']);  // only works in a separate call (!?)
}
