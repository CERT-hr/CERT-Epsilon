window.onload = function() {

    $('form').submit(function () {
	    $('input[type="submit"]').hide();
	    $('.loader').show();
    })

    var activePath = $('html').data('path');
    $('.nav-item a[href="' + activePath + '"]').addClass("active");

    $("#example-date-input").hide();
    $("#example-date-input2").hide();
}

$('nav nav-pills-links > li > a').on('click', function(e) {
    $('nav nav-pills-links > li > a').removeClass('active');
    $(this).addClass('active');
});

$('#pagination-div > nav > ul > li').on('click', function(e) {
    $('#pagination-div > nav > ul > li').removeClass('active');
    $(this).addClass('active');
});

$(document).ready(function () {

    $('[data-toggle="popover"]').popover();

    $("#show-all-entries-tab").click(function() {
        $("#top-10-tab").hide();
        $("all-entries-tab").show();
        $("#pagination-div").show();
    });
    $("#show-top-10-tab").click(function() {
        $("#top-10-tab").show();
        $("all-entries-tab").hide();
        $("#pagination-div").hide();
    });
    
    const source = document.getElementById('per_page_input');
    const result = document.getElementById('number_of_pages');
    search = false;
    page_number = 1;

    const inputHandler = function(e) {
        page_number = source.value;
        result.innerHTML = "+";
        result.classList.remove("btn-light");
        result.classList.add("btn-success");
        search = true
        result.onclick=paginate;
    }

    source.addEventListener('input', inputHandler);
    source.addEventListener('propertychange', inputHandler); // for IE8
    // Firefox/Edge18-/IE9+ don’t fire on <select><option>
    source.addEventListener('change', inputHandler);

    const paginate = function(e){
        if(search){
            var url = new URL(location.href);
            url.searchParams.set('p', page_number);
            location.href=url;
        }
    }
    //result.addEventListener("onclick", paginate);

    $("*[rel=tooltip]").tooltip();
});


function handle_per_page(v){
    var url = new URL(location.href);
    url.searchParams.set('p', 1);
    url.searchParams.set('pp', v);
    location.href=url;
}

function handle_date_pick_change(picker){
    $("#example-date-input").hide();
    $("#example-date-input2").hide();
    $("#example-date-input").attr("disabled", false);
    $("#example-date-input2").attr("disabled", false);
    switch(picker.value){
        case "from":
            $("#example-date-input").show();
            $("#example-date-input2").attr("disabled", true);
            break;
        case "until":
            $("#example-date-input2").show();
            $("#example-date-input").attr("disabled", true);
            break;
        case "between":
            $("#example-date-input").show();
            $("#example-date-input2").show();
            break;
    }
}

function custom_submit(){
    $('#filter_form > input:hidden').attr("disabled",true);
    $('#filter_form').submit();
}
