// Resamples the shared transparent fedora mark into macOS iconset PNGs.
// Uses CoreGraphics/ImageIO so it runs without a WindowServer.
// clang -fobjc-arc -framework Foundation -framework CoreGraphics \
//       -framework ImageIO make-icon.m -o make-icon
// ./make-icon out.png 1024 ../static/agent-b-logo.png
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 4) {
            fprintf(stderr, "usage: make-icon output.png size logo.png\n");
            return 1;
        }
        NSString *outPath = [NSString stringWithUTF8String:argv[1]];
        const NSInteger size = atoi(argv[2]);
        if (size < 16 || size > 4096) {
            fprintf(stderr, "invalid icon size\n");
            return 1;
        }
        NSURL *sourceURL = [NSURL fileURLWithPath:[NSString stringWithUTF8String:argv[3]]];
        CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)sourceURL, NULL);
        CGImageRef mark = source ? CGImageSourceCreateImageAtIndex(source, 0, NULL) : NULL;
        if (!mark) {
            if (source) CFRelease(source);
            fprintf(stderr, "cannot read logo\n");
            return 1;
        }
        CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        CGContextRef context = CGBitmapContextCreate(NULL, size, size, 8, 0, space,
            kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
        if (!context) {
            CGImageRelease(mark); CFRelease(source); CGColorSpaceRelease(space);
            fprintf(stderr, "cannot create image context\n");
            return 1;
        }
        CGFloat width = CGImageGetWidth(mark), height = CGImageGetHeight(mark);
        CGFloat scale = MIN(size / width, size / height);
        CGRect bounds = CGRectMake((size - width * scale) / 2,
            (size - height * scale) / 2, width * scale, height * scale);
        CGContextSetInterpolationQuality(context, kCGInterpolationHigh);
        CGContextDrawImage(context, bounds, mark);
        CGImageRef image = CGBitmapContextCreateImage(context);
        NSURL *outputURL = [NSURL fileURLWithPath:outPath];
        CGImageDestinationRef destination = CGImageDestinationCreateWithURL(
            (__bridge CFURLRef)outputURL, CFSTR("public.png"), 1, NULL);
        BOOL success = NO;
        if (destination) {
            CGImageDestinationAddImage(destination, image, NULL);
            success = CGImageDestinationFinalize(destination);
            CFRelease(destination);
        }
        CGImageRelease(image); CGContextRelease(context); CGColorSpaceRelease(space);
        CGImageRelease(mark); CFRelease(source);
        if (!success) fprintf(stderr, "cannot write icon PNG\n");
        return success ? 0 : 1;
    }
}
