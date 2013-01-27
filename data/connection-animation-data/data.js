var image_path = "images/old-computer.png";

// function is called from animation context
// to set nodes
function main() {

		register_packet(   0, r1, r2, 'syn',    30, 2000);

		register_packet( 2000, r2, r1, 'syn',    30, 2000);
		register_packet( 4000, r1, r2, 'syn',    30, 2000);
		register_packet( 6020, r1, r2, 'data', 1000, 2000);
		register_packet( 6500, r1, r2, 'data',  1000, 2000);
		register_packet( 6800, r1, r2, 'data',  1000, 2000);
		register_packet( 8900, r2, r1, 'pure-ack',    30, 2000);
		register_packet( 10900, r1, r2, 'data',  1000, 2000);
		register_packet( 11000, r1, r2, 'data',  1000, 2000);
		register_packet( 13000, r2, r1, 'fin',    30,2000);
		register_packet( 15000, r1, r2, 'fin',    30, 2000);
}

