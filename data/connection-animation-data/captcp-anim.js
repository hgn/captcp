// Captcp
// http://research.protocollabs.com/captcp
//
// JavaScript: WTF - not my language ... ;-(


function scale_packet(packet_len) {
	var min_len = 4;
	var max_len = 10;

	var new_len = packet_len / max_len;

	if (new_len < min_len)
		new_len = min_len;


	return new_len;
};



function wndsize(){
	var w = 0;
	var h = 0;

	//IE
	if(!window.innerWidth){
		if(!(document.documentElement.clientWidth == 0)){
			//strict mode
			w = document.documentElement.clientWidth;h = document.documentElement.clientHeight;
		} else{
			//quirks mode
			w = document.body.clientWidth;h = document.body.clientHeight;
		}
	} else {
		w = window.innerWidth;h = window.innerHeight;
	}
	return {width:w,height:h};
}


function viewport() {
	var e = window
		, a = 'inner';
	if ( !( 'innerWidth' in window ) )
	{
		a = 'client';
		e = document.documentElement || document.body;
	}
	return { width : e[ a+'Width' ] , height : e[ a+'Height' ] }
}


window.onload = function () {

	var windowsize = wndsize();
	var paper = Raphael("canvas", window.innerWidth, 250);
	var btn   = document.getElementById("run");
	var btn_stop   = document.getElementById("stop");
	var id = 0;

	draw_packet = function(src, dst, packet_type, packet_len, duration) {

		var packet_color = "#999999";

		switch(packet_type)
		{
			case 'syn':
				packet_color = "#00ff00";
				break;
			case 'pure-ack':
				packet_color = "#0000ff";
				break;
			case 'fin':
				packet_color = "#ff0000";
				break;
			default:
				break;
		};

		var x = paper.rect(src.attr('x') + 40, 140, scale_packet(packet_len), 50, 1);
		x.toBack();
		x.attr({fill: packet_color, stroke: '#000000', 'stroke-width': 2});
		x.animate({x: dst.attr('x') + 50, y: 140}, duration);
	};


	register_packet = function(time_start, src, dst, packet_type, packet_len, duration) {
		id = window.setTimeout ( function() { draw_packet(src, dst, packet_type, packet_len, duration) }, time_start);
	};

	btn_stop.onclick = function () {
		while (id--) {
			window.clearTimeout(id);
		}
	};


	(btn.onclick = function () {


		// clear all timeouts
		while (id--) {
			window.clearTimeout(id);
		}

		//var cd    = document.getElementById("code");
		//var speed = document.getElementById("speed");
		//var cmd = " " + cd.value + " " + speed.value + ");";

		var img = document.createElement('img');
		img.src='images/old-computer.png';

		paper.clear();


		r1 = paper.image(image_path, 10, 50, img.width, img.height);
		r1.toFront();
		r1.attr({'z-index': -1 });
		r2 = paper.image(image_path, window.innerWidth - 200, 50, img.width, img.height);
		r2.attr({'z-index': -1 });
		r2.toFront();

		main();

		var text_time = paper.text(50, 50, "");
		text_time.attr('text', 'time: 0');


		try {
			(new Function("paper", "window", "document")).call(paper, paper);
		} catch (e) {
			alert(e.message || e);
		}
	})();
};
