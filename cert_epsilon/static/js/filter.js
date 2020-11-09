if (!String.prototype.format) {
    String.prototype.format = function() {
      var args = arguments;
      return this.replace(/{(\d+)}/g, function(match, number) { 
        return typeof args[number] != 'undefined'
          ? args[number]
          : match
        ;
      });
    };
}
var vendor_row_template = `<div id="selected_values" class="row {0}">
                      <div class="col-8 selected_value selected_{0} center-div-items">{0}</div>
                      <div onclick="remove_vendor(event,'{0}')" onmouseover="add_effect('selected_{0}')" onmouseleave="remove_effect('selected_{0}')" class="col-2">
                        <button type="button" class="close" aria-label="Close">
                          <span aria-hidden="true">&times;</span>
                        </button> <input type="hidden" name="vendor" value="{0}"> 
                      </div>
                    </div>`;

var SELECTED_VENDOR;
var added_vendors = []
function remove_vendor(e,vendor){
    added_vendors.splice(added_vendors.indexOf(vendor),1);
    $('.'+vendor).remove();
    e.stopPropagation();
}

function add_vendor() {
    if(SELECTED_VENDOR != null && added_vendors.indexOf(SELECTED_VENDOR)==-1 ) {
        $("#selected_values_wrapper").append(vendor_row_template.format(SELECTED_VENDOR))
        added_vendors.push(SELECTED_VENDOR);
        SELECTED_VENDOR = null;
    }
}

function add_effect(v){
    if(typeof v == 'string'){
        $('.'+v).animate({backgroundColor: '#5bc0de'},200);
    }else{
        $(v).animate({backgroundColor: '#5bc0de'},200);
    }
    
}

function remove_effect(v){
    if(typeof v == 'string'){
        $('.'+v).animate({backgroundColor: ''},100);
    }else{
        $(v).animate({backgroundColor: ''},100);
    }
}

function os_click(f) {
    var status = $(f).is(":checked") ? true : false;
    var type = f.value;
    $('.form-check-input.' + type).prop('checked', status);
}

$.getJSON( "/api/get_vendors", function( data, status, xhr ) {
    var vendor_names = [];
    for (var i = 0; i < data.length; i++) {
        vendor_names.push(data[i]["name"]);
    }
    $("input#vendor_autocomplete").autocomplete({
        source: vendor_names,
        autoFocus: true,
        response: function (event, ui) {
            if (!ui.content.length) {
                var noResult = { value: "", label: "No results found" };
                ui.content.push(noResult);
            }
        },
        minLength: 3,
        select: function (e, i) {
            SELECTED_VENDOR = i.item.value;
            add_vendor(SELECTED_VENDOR);
            $(this).val("");
            e.stopPropagation();
            return false;
        }
    })
});
