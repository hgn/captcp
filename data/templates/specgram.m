function [B,f,t] = specgram(a,nfft,fs,window,numoverlap)
%       B = specgram(a)
%       B = specgram(a,nfft)
%   [B,f] = specgram(a,nfft,fs)
% [B,f,t] = specgram(a,nfft,fs)
%       B = specgram(a,nfft,fs,window)
%       B = specgram(a,nfft,fs,window,numoverlap)
%           specgram(a)
%       B = specgram(a,f,fs,window,numoverlap)
%
% Defaults:
%         nfft = min(256,length(a))
%           fs = 2
%       window = hanning(nfft)
%   numoverlap = length(window)/2
%
% http://www.mathworks.com/access/helpdesk_r13/help/toolbox/signal/specgram.html


% Defaults
if nargin < 2 || isempty(nfft)
    nfft = min(256, length(a));
end
if nargin < 3 || isempty(fs)
    fs = 2;
end
if nargin < 4 || isempty(window)
    window = hanning(nfft);
end
if nargin < 5 || isempty(numoverlap)
    numoverlap = fix(length(window)/2);
end

if isscalar(window)
    window = hanning(window);
end

% Sanity checks
if length(window) > nfft
    error("The window length must be no greater than the FFT length.");
end
if numoverlap >= length(window)
    error("numoverlap must be strictly less than the window length.");
end
if nfft <= 0 || numoverlap <= 0
    error("nfft and numoverlap must be positive.");
end
if !isvector(a)
    error("Requires vector input.");
end

% vars
a = vec(a);
n = length(a);
w = length(window);
k = fix((n-numoverlap)/(w-numoverlap));

% if it's real we only want the first half of the bins
nr = nfft;
if isreal(a)
    nr = ceil((nfft+1)/2);
end

% preallocate
B = zeros(nr, k);

% calculation
planner = fftw('planner');
fftw('planner', 'patient');
for x = 1:k
    y = (x-1)*(w-numoverlap);
    B(:,x) = fft(a(y+1:y+w).*window,nfft)(1:nr);
end
fftw('planner', planner);

% output
f = (0:nr-1) * fs/nfft;
t = (0:k-1) * (w-numoverlap) / fs;
if nargout == 0
    imagesc(t,f,20*log10(abs(B))), \
        axis xy, xlabel('seconds'), ylabel('Hz'), colormap(jet);
    clear B;
end
