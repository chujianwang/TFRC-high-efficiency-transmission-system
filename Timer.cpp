class Timer{
	clock_t start, finish;
	double duration
	
	void Start(){
		start=clock();
	}
	
	void Finish(){
		finish=clock();
	}
	
	double Duration(){
		return duration= (double)(finish - start) / CLOCKS_PER_SEC;
	}
}
